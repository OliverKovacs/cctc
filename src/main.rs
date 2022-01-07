// Oliver Kovacs 2021 - cctc - MIT

use std::fs;
use std::time::Instant;
use std::collections::HashMap;
use std::io::{stdout, Write};
use regex::Regex;
use clap::ArgMatches;

mod app;

fn encrypt(cleartext: &String, key: &Vec<usize>) -> String {
    let size_x = key.len();
    let size_y = cleartext.len() / size_x;
    let mut lookup = vec!(0; size_x);
    let mut key = key.clone();
    key.reverse();
    key
        .iter()
        .enumerate()
        .for_each(|(i, index)| lookup[*index] = i);

    let mut out: Vec<char> = vec!(' '; cleartext.len());
    for (i, character) in cleartext.chars().enumerate() {
        let x = lookup[i % size_x];
        let y = i / size_x;
        out[x * size_y + y] = character;
    }
    out.iter().collect()
}

fn decrypt(cipher: &String, key: &Vec<usize>) -> String {
    let size_x = key.len();
    let size_y = cipher.len() / size_x;
    let mut lookup = vec![0; size_x];
    let mut key = key.clone();
    key.reverse();
    key
        .iter()
        .enumerate()
        .for_each(|(i, index)| lookup[*index] = i);
    
    let mut out: Vec<char> = vec!(' '; cipher.len());
    for (i, character) in cipher.chars().enumerate() {
        let x = lookup[i / size_y];
        let y = i % size_y;
        out[y * size_x + x] = character;
    }
    out.iter().collect()
}

pub fn factorial(num: usize) -> usize {
    match num {
        0 => 1,
        _ => (1..num + 1).product(),
    }
}

fn lehmer_to_permutation<T: Clone>(list: &Vec<T>, code: &Vec<usize>) -> Vec<T> {
    let mut out: Vec<T> = Default::default();
    let mut list = list.clone();
    for i in code {
        out.push(list[*i].clone());
        list.remove(*i);
    }
    out
}

fn index_to_lehmer(index: usize, size: usize) -> Vec<usize> {
    if size <= 1 {
        let out: Vec<usize> = vec!(0);
        return out;
    }
    let multiplier = factorial(size - 1);
    let digit = index / multiplier;
    let mut next: Vec<usize> = index_to_lehmer(index % multiplier, size - 1);
    let mut out: Vec<usize> = vec!(digit);
    out.append(&mut next);
    out
}

fn generate_permutations(cipher: &String, mut out: &mut Vec<String>, permutations: Vec<Vec<usize>>, n: &Vec<usize>, index: usize) -> () {
    if n.len() == 0 {
        let combinations = factorial(permutations.len());
        if index % 10000 == 0 {
            print!("\r{:.2}%", 100f32 * index as f32 * combinations as f32 / out.len() as f32);
            stdout().flush().unwrap();
        }
        let list = (0..combinations).collect::<Vec<usize>>();
        for i in 0..combinations {
            let mut string = cipher.clone();
            let code = index_to_lehmer(i, permutations.len());
            let result = lehmer_to_permutation(&list, &code);
            for j in 0..permutations.len() {
                string = decrypt(&string, &permutations[result[j]]);
            }
            out[index * combinations + i] = string;
        }
        return;
    }

    let list = (0..*n.last().unwrap()).collect::<Vec<usize>>();

    let mut new_n = n.clone();
    new_n.pop();
    let length: usize = new_n
        .iter()
        .map(|e| factorial(*e))
        .product();

    for i in 0..factorial(*n.last().unwrap()) {
        let code = index_to_lehmer(i, *n.last().unwrap());
        let result = lehmer_to_permutation(&list, &code);
        let mut permutations = permutations.clone();
        permutations.push(result);
        generate_permutations(cipher, &mut out, permutations, &new_n, index + i * length);
    }
}

fn permutations_length(n: &Vec<usize>) -> usize {
    factorial(n.len()) * n
        .iter()
        .map(|e| factorial(*e))
        .product::<usize>()
}

fn encrypt_cmd(matches: &ArgMatches) -> () {
    let plaintext = String::from(matches.value_of("PLAINTEXT").unwrap());
    let key = matches
        .value_of("KEY")
        .unwrap()
        .split("-")
        .map(|e| e.parse::<usize>().unwrap())
        .collect::<Vec<usize>>();

    println!("\"{}\"", encrypt(&plaintext, &key));
}

fn decrypt_cmd(matches: &ArgMatches) -> () {
    let cipher = String::from(matches.value_of("CIPHER").unwrap());
    let key = matches
        .value_of("KEY")
        .unwrap()
        .split("-")
        .map(|e| e.parse::<usize>().unwrap())
        .collect::<Vec<usize>>();

    println!("\"{}\"", decrypt(&cipher, &key));
}

fn crack_cmd(matches: &ArgMatches) -> () {

    let now = Instant::now();

    println!("creating list ... {:?}", now.elapsed());
    let mut list = create_list(matches);
    println!("done! ({} words) {:?}", list.len(), now.elapsed());

    println!("filtering list ... {:?}", now.elapsed());
    list = filter_list(list, matches);
    println!("done! ({} words) {:?}", list.len(), now.elapsed());

    if matches.is_present("LIST_OUTPUT") {
        println!("saving list ... {:?}", now.elapsed());
        save_list(&list, matches);
        println!("done! {:?}", now.elapsed());
    }

    println!("creating dictonary ... {:?}", now.elapsed());
    let dictonary = create_dictonary(matches);
    println!("done! ({} words) {:?}", dictonary.len(), now.elapsed());

    println!("filtering dictonary ... {:?}", now.elapsed());
    let dictonary = filter_dictonary(dictonary, matches);
    println!("done! ({} words) {:?}", dictonary.len(), now.elapsed());

    println!("run attack ... {:?}", now.elapsed());
    let results = run_attack(list, dictonary);
    println!("done! ({} highest) {:?}", results[0].1, now.elapsed());

    println!("saving to file ...");
    save_output(results, matches);
    println!("done!")
}

fn create_list(matches: &ArgMatches) -> Vec<String> {

    if matches.is_present("FILE") {
        let file = matches.value_of("FILE").unwrap();
        let mut list = fs::read_to_string(file)
            .unwrap()
            .split('\n')
            .map(|e| String::from(e))
            .collect::<Vec<String>>();

        list.pop();
        return list;
    }

    let cipher = String::from(matches.value_of("CIPHER").unwrap()).to_lowercase();
    let columns = matches
        .value_of("COLUMNS")
        .unwrap()
        .split("-")
        .map(|e| e.parse::<usize>().unwrap())
        .collect::<Vec<usize>>();

    let mut list = vec!(String::new(); permutations_length(&columns));
    generate_permutations(&cipher, &mut list, vec!(vec!(0; 0); 0), &columns, 0);
    print!("\n");
    list
}

fn filter_list(mut list: Vec<String>, matches: &ArgMatches) -> Vec<String> {
    if matches.is_present("FILTER_BEGINS_WITH_SPACE") {
        list = filter_begins_with_space(list);
    }
    if matches.is_present("FILTER_DOUBLE_SPACE") {
        list = filter_double_space(list);
    }
    if matches.is_present("FILTER_NO_VOWELS") {
        list = filter_no_vowels(list);
    }
    if matches.is_present("FILTER_MUST_CONTAIN") {
        list = filter_must_contain(&list, &String::from(matches.value_of("FILTER_MUST_CONTAIN").unwrap()));
    }
    list
}

fn filter_begins_with_space(vector: Vec<String>) -> Vec<String> {
    vector
        .into_iter()
        .filter(|e| e.chars().next().unwrap() != ' ')
        .collect()
}

fn filter_double_space(vector: Vec<String>) -> Vec<String> {
    let regex = Regex::new(r"\s\s\S").unwrap();
    vector
        .into_iter()
        .filter(|e| !regex.is_match(e))
        .collect()
}

fn filter_no_vowels(vector: Vec<String>) -> Vec<String> {
    let regex = Regex::new(r"\s[^ei\s]+\s").unwrap();
    vector
        .into_iter()
        .filter(|e| !regex.is_match(&format!(" {} ", e)[..]))
        .collect()
}

fn filter_must_contain(vector: &Vec<String>, string: &String) -> Vec<String> {
    let string = format!(" {} ", string);
    vector
        .into_iter()
        .map(|e| format!(" {} ", e))
        .filter(|e| e.contains(&string))
        .collect()
}

fn save_list(list: &Vec<String>, matches: &ArgMatches) -> () {
    let path = matches.value_of("LIST_OUTPUT").unwrap();

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(b"").unwrap();
    file.flush().unwrap();

    let mut file = fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(path)
        .unwrap();

    list.iter().for_each(|e| write!(file, "{}\n", e).unwrap());
}

fn create_dictonary(matches: &ArgMatches) -> Vec<String> {
    let dictonary = matches.value_of("DICTONARY").unwrap();
    let mut words = fs::read_to_string(dictonary)
        .unwrap()
        .split("\r\n")
        .map(|e| String::from(e).to_lowercase())
        .collect::<Vec<String>>();
    
    words.pop();
    words
}

fn filter_dictonary(mut dictonary: Vec<String>, matches: &ArgMatches) -> Vec<String> {
    let cipher = String::from(matches.value_of("CIPHER").unwrap()).to_lowercase();
    dictonary = filter_words_length(dictonary, &cipher);
    dictonary = filter_words_characters(dictonary, &cipher);

    dictonary
        .into_iter()
        .map(|e| format!(" {} ", e))
        .collect::<Vec<String>>()
}

fn filter_words_length(words: Vec<String>, cipher: &String) -> Vec<String> {
    let n = cipher.len();
    words
        .into_iter()
        .filter(|e| e.len() <= n)
        .collect::<Vec<String>>()
}

fn filter_words_characters(words: Vec<String>, cipher: &String) -> Vec<String> {
    let mut map: HashMap<char, i64> = HashMap::new();

    cipher.chars().for_each(|e| {
        let amount = map.entry(e).or_insert(0);
        *amount += 1;
    });

    words
        .into_iter()
        .filter(|word| {
            let mut map = map.clone();
            let mut out = true;
            word.chars().for_each(|e| {
                let amount = map.entry(e).or_insert(0);
                *amount -= 1;
                if *amount < 0 { out = false; }
            });
            out
        })
        .collect::<Vec<String>>()
}

fn run_attack(list: Vec<String>, dictonary: Vec<String>) -> Vec<(String, usize, Vec<String>)> {
    let mut results = list
        .iter()
        .map(|e| format!(" {} ", e))
        .enumerate()
        .map(|(i, word)| {
            let mut count: usize = 0;
            let mut hits: Vec<String> = Default::default();
            for string in dictonary.clone() {
                if !word.contains(&string) { continue; }
                count += 1;
                hits.push(string);
            }

            if i % 100 == 0 {
                print!("\r{:.2}%", 100f32 * i as f32 / list.len() as f32);
                stdout().flush().unwrap();
            }

            (word, count, hits)
        })
        .collect::<Vec<(String, usize, Vec<String>)>>();
    
    print!("\n");
    results.sort_by(|a, b| b.1.cmp(&a.1));
    results
}

fn save_output(sum: Vec<(String, usize, Vec<String>)>, matches: &ArgMatches) -> () {
    let path = matches.value_of("OUTPUT").unwrap();
    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .unwrap();

    file.write_all(b"").unwrap();
    file.flush().unwrap();

    sum.into_iter().for_each(|e| write!(file, "{} {} {:?}\n", e.1, e.0, e.2).unwrap());
    file.flush().unwrap();
}

fn main() {
    match app::app().subcommand() {
        Some(("encrypt", sub_matches)) => encrypt_cmd(sub_matches),
        Some(("decrypt", sub_matches)) => decrypt_cmd(sub_matches),
        Some(("crack", sub_matches)) => crack_cmd(&sub_matches),
        _ => unreachable!(),
    }
}
